import requests, os
from time import sleep
from sys import argv
from platform import system as platform_system
from yaml import safe_load, safe_dump
from datetime import datetime
from socket import socket, AF_INET, SOCK_RAW
try:
    from tqdm import tqdm
except ModuleNotFoundError:
    print('Módulo tqdm no encontrado. Ejecute "pip install tqdm" para obtenerlo.')

def clear_screen():
    '''Limpiar pantalla.'''
    clear_msg = 'cls' if platform_system() == 'Windows' else ('clear' if platform_system() == 'Linux' else '')
    os.system(clear_msg)
    return 0

def ping(host:str, timeout:float=1.0):
    sock = socket(AF_INET, SOCK_RAW, 1)
    sock.settimeout(timeout)
    try:
        sock.connect((host, 0))
    except Exception:
        return 1
    sock.send(b'\x08\x00\xf7\xff\x00\x00\x00\x00')
    try:
        r = sock.recv(1024)
    except TimeoutError:
        return 1
    sock.close()
    if r:
        return 0
    return 1

class EtecsaLogger():
    ruta_script = os.path.dirname(argv[0]).replace('\\', '/')
    logger_data_folder = ruta_script + '/logger_data/'
    HOST = 'https://secure.etecsa.net:8443'
    login_endpoint = '/LoginServlet'
    logout_endpoint = '/LogoutServlet'
    get_time_endpoint = '/EtecsaQueryServlet'

    def __init__(self):
        self.__load_yaml('users'); self.__load_yaml('config')
        try:
            self.user_pass = self.users[self.config['choose']]
        except KeyError:
            raise KeyError('El usuario indicado en el archivo de configuración config.yaml no existe en el archivo users.yaml. Agrégalo e inténtalo de nuevo')
        self.attribute_uuid = None
        self.session_start_time = None
        self.initial_left_time = None
        self.connection_type = None
        self._load_session_data(True if len(argv) == 1 and __name__ == '__main__' else False)

    def __load_yaml(self, file_name:str, return_dict:bool=False):
        '''Función encargada de cargar los datos especificados del archivo ./logger_data_folder/users.yaml o ./logger_data_folder/config.yaml según se especifique.

        file_name: [ 'users' | 'config' ]
        '''
        msgs = {'users': '''!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Archivo users.yaml con los usuarios y sus respectivas contraseñas {type_of_error}.
Cree el archivo {logger_data_folder}users.yaml, el cual contenga la información de los usuarios con el siguiente formato:

usuario1@nauta.com.cu:
  username: usuario1
  password: usuario1_pass
usuario2@nauta.co.cu:
  username: usuario2
  password: usuario2_pass''',
                'config': '''!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Archivo config.yaml con la configuración {type_of_error}.
Cree un archivo {logger_data_folder}config.yaml, con un par clave: valor.
El valor debe ser un correo existente dentro del archivo {logger_data_folder}users.yaml. Por ejemplo:

choose: usuario1@nauta.com.cu'''}
        assert file_name in ['users', 'config'], 'Parámetro file_name inválido.'

        def make_example(file_route, file_name):
            content = {'example1@nauta.com.cu': {'username': 'example1@nauta.com.cu', 'password': 'example1'},
                       'example2@nauta.co.cu': {'username': 'example2@nauta.co.cu', 'password': 'example2'  }} if file_name == 'users' \
                        else {'choose':'example1@nauta.com.cu'}
            os.makedirs(file_route, exist_ok=True)
            with open(file_route+file_name+'.yaml', 'w') as file:
                safe_dump(content, file)

        def ask_for_example(file_route, file_name):
            e = input('\nDesea crear un ejemplo de archivo? (Y/N) ')
            if e.lower() == 'y':
                make_example(file_route, file_name)
                print('Archivo %s.yaml creado con éxito.'%(file_route+file_name))

        for i in range(2):
            try:
                file_route = self.logger_data_folder + '{name}.{extension}'.format(name=file_name, extension=['yml', 'yaml'][i])
                with open(file_route, 'r') as file:
                    content = safe_load(file)
                    exc = 0
                    if not isinstance(content, dict):
                        exc = 1
                    elif file_name == 'config' and 'choose' not in content:
                        exc = 1
                    if exc:
                        print(msgs[file_name].format(logger_data_folder=self.logger_data_folder,
                                                     type_of_error='inválido'))
                        ask_for_example(self.logger_data_folder, file_name)
                        exit(1)
                    exec('self.%s = content'%file_name)
                    return
            except FileNotFoundError:
                if i == 1:
                    print(msgs[file_name].format(logger_data_folder=self.logger_data_folder,
                                                 type_of_error='no encontrado'))
                    ask_for_example(self.logger_data_folder, file_name)
                    exit(1)

    def save_config(self, username:str):
        '''Función encargada de guardar la configuracion del nuevo usuario a usar en el archivo config.yaml.
        '''
        msg_err = 'Formato inválido. Ingrese un correo del tipo: \'@nauta.com.cu\' o \'@nauta.co.cu\''
        if self.attribute_uuid != None:
            print('Cierre sesión primero y después cambie el usuario a usar.')
            return 1
        users = list(self.users.keys())
        ___ = [user.startswith(username) for user in users]
        if ___.count(True) == 1:
            username = users[___.index(True)]
            print('Se ha elegido por las iniciales al usuario: %s'%username)
        if not any([username.endswith(i) for i in ['@nauta.com.cu', '@nauta.co.cu']]):
            print(msg_err)
            return 1
        if not username in self.users.keys():
            print('Correo electrónico inválido. Elija uno entre los siguientes correos:')
            for i in self.users.keys():
                print(i, end='\n', flush=True)
            return 1
        with open(self.logger_data_folder+'config.yaml' if os.access(self.logger_data_folder+'config.yaml', os.F_OK) else self.logger_data_folder+'config.yml', 'w') as file:
            self.config['choose'] = username
            self.user_pass = self.users[username]
            safe_dump(self.config, file)
        return 0

    def __update_session_data(self, response:requests.Response):
        '''Función encargada de analizar la respuesta de inicio de sesión y extraer el parámetro
        ATTRIBUTE_UUID y crear la variable session_start_time a partir de la hora actual.
        '''
        self.session_start_time = datetime.now()
        location_attribute_uuid = response.text.find('ATTRIBUTE_UUID=')
        if location_attribute_uuid != -1:
            self.attribute_uuid = response.text[location_attribute_uuid+15:location_attribute_uuid+15+32]  # 15 = len('ATTRIBUTE_UUID=')
        else:
            self.session_start_time = None
            return 1
        return 0

    def __save_session_data(self):
        '''Función encargada de guardar los datos en el archivo internet_session.yaml.
        '''
        os.makedirs(self.logger_data_folder, exist_ok=True)
        try:
            with open(self.logger_data_folder+'internet_session.yaml' if os.access(self.logger_data_folder+'internet_session.yaml', os.F_OK) else self.logger_data_folder+'internet_session.yml', 'w') as file:
                safe_dump({'ATTRIBUTE_UUID': self.attribute_uuid,
                        'session_start_time': str(self.session_start_time) if self.session_start_time != None else None,
                        'initial_left_time': self.initial_left_time if self.initial_left_time != None else None,
                        'connection_type':self.connection_type},
                            file)
        except FileNotFoundError:
            print('Archivo %sinternet_session.yaml no encontrado!'%self.logger_data_folder)
            return 1
        return 0

    def _load_session_data(self, verbose:bool=False):
        '''Función encargada de cargar los datos de sesión del archivo internet_session.yaml.
        '''
        for i in range(2):
            try:
                ok = [0, 0, 0, 0]
                with open(self.logger_data_folder + 'internet_session.%s'%['yml', 'yaml'][i], 'r') as file:
                    content = safe_load(file)
                    self.attribute_uuid = content['ATTRIBUTE_UUID']
                    ok[0] = 1
                    self.initial_left_time = content['initial_left_time']
                    ok[1] = 1
                    self.connection_type = content['connection_type']
                    ok[2] = 1
                try:
                    self.session_start_time = datetime.fromisoformat(content['session_start_time'])
                    ok[3] = 1
                except TypeError:
                    self.session_start_time = None
                if all(ok) and verbose:
                    print('Datos de sesión cargados con éxito.') if verbose else None
                return
            except FileNotFoundError:
                print('Archivo con los datos de sesión no encontrado.') if (verbose and i == 1) else None

    def __html(self, source:bytes|str, name_of_html='response.html', save=True):
        '''Función encargada de trabajar con el archivo html que responde el servidor.
        save:   Guarda el archivo html en la ruta self.logger_data_folder/response.html si save es True, de otra manera lo elimina si es que existe.'''
        if not isinstance(source, (bytes, str)):
            raise TypeError('El argumento -> source <- debe ser de tipo bytes o str')
        if not isinstance(name_of_html, str):
            raise TypeError('El argumento -> name_of_html <- debe ser de tipo str')
        if isinstance(save, bool):
            abs_route = self.logger_data_folder + name_of_html
            if save:
                if self.attribute_uuid:
                    with open(abs_route, 'wb' if isinstance(source, bytes) else 'w') as file:
                        file.write(source)
                    return 0
                return 1
            else:
                if os.access(abs_route, os.F_OK):
                    try:
                        os.remove(abs_route)
                    except PermissionError:
                        print('No tiene suficientes permisos para eliminar el archivo html: {}'.format(abs_route))
                    return 0
                return 1
        else:
            raise Exception('Llamada a la función EtecsaLogger.html() incorrecta. Especifique el parámetro save como True o False')

    def get_left_time_from_server(self, return_str:bool=True):
        '''Función encargada de obtener el tiempo restante de la sesión al momento de crearla.
        '''
        if self.attribute_uuid:
            try:
                response = requests.post(url=self.HOST+self.get_time_endpoint, data={'op':'getLeftTime', 'username':self.user_pass['username'], 'ATTRIBUTE_UUID':self.attribute_uuid}, timeout=10)
            except requests.exceptions.SSLError:
                return None
            if response.text != 'errorop':
                if return_str:
                    return response.text
                else:
                    self.initial_left_time = response.text
            else:
                self.reestablecer_variables()
        return 1

    def onTime(self):
        '''Función encargada de devolver el tiempo que la sesión ha estado activa.
        '''
        onTime = 0
        if isinstance(self.session_start_time, datetime):
            onTime = (datetime.now() - self.session_start_time).total_seconds()
        return onTime

    def get_left_time(self): # ATTRIBUTE_UUID: 78FB543ABFCB554F0467DF10DE2535AE
        '''Función encargada de calcular el tiempo restante de la sesión. (Si es que existe alguna.)
        '''
        if not self.attribute_uuid:
            return 'No existen los datos de la sesión.'
        try:
            hours, minutes, seconds = map(lambda x:int(x), self.initial_left_time.split(':'))
        except AttributeError:
            return '??:??:??'
        time = hours*3600 + minutes*60 + seconds
        on_time = self.onTime()
        left_time = time - on_time
        if left_time < 0:
            return 'Se agotó el tiempo de la sesión.'
        left_hours = left_time//3600
        left_minutes = (left_time%3600)//60
        left_seconds = ((left_time%3600)%60)
        return '%.2d:%.2d:%.2d' %(left_hours, left_minutes, left_seconds)

    def reestablecer_variables(self, save_to_file:bool=False):
        self.attribute_uuid, self.session_start_time, self.initial_left_time, self.connection_type = [None for i in range(4)]
        if save_to_file:
            self.__save_session_data()

    def _check_connection(self, timeout:float=1):
        '''Función encargada de chequear si existe conexión a internet.
        timeout:    Tiempo máximo del ping, en segundos.
        '''
        internet, intranet = None, None
        internet = True if ping('8.8.8.8', timeout) == 0 else False
        if not internet:
            intranet = True if ping('190.92.127.78', timeout) == 0 else False
        return 'internet' if internet else ('intranet' if intranet else None)

    def login(self, verbose:bool=True, return_str:bool=False):
        '''Función encargada de iniciar la sesión de internet.
        '''
        hay_conexion = self._check_connection()
        if not hay_conexion:
            #Peticion POST a /LoginServlet con los datos username y password.
            exception = 1
            try:
                response = requests.post(url=self.HOST+self.login_endpoint, data=self.user_pass, allow_redirects=True)
                exception = 0
            except requests.exceptions.ConnectionError:
                msg = 'Hubo un error al realizar la petición. Inténtelo de nuevo.'
            except requests.exceptions.Timeout:
                msg = 'El servidor no respondió en un tiempo dado.'
            if exception:
                print(msg) if verbose else None
                return msg if return_str else 1
            self.__update_session_data(response)
            self.initial_left_time = self.get_left_time_from_server()
            if 'Su tarjeta no tiene saldo disponible.' in response.text:
                self.reestablecer_variables(True)
                msg = 'La cuenta no tiene saldo disponible.'
                print(msg) if verbose else None
                return msg if return_str else 1
            elif 'No se pudo autorizar al usuario.' in response.text:
                self.reestablecer_variables(True)
                msg = 'Usuario o contraseña inválidos.'
                print(msg) if verbose else None
                return msg if return_str else 1
            self.__html(response.content, save=True) # For debugging
            self.connection_type = 'internet' if self.user_pass['username'].endswith('@nauta.com.cu') else 'intranet'
            self.__save_session_data()
            msg = 'Conexión a {connection_type} creada.\nCuenta: {username}\nTiempo disponible: {left_time}'.format(connection_type=self.connection_type.upper(), username=self.user_pass['username'], left_time=self.initial_left_time)
            print(msg) if verbose else None
            return msg if return_str else 0
        else:
            msg = 'Ya hay conexión. (%s)'%hay_conexion
            print(msg) if verbose else None
            return msg if return_str else 1

    def logout(self, verbose:bool=True, return_str:bool=False):
        '''Función encargada de cerrar la sesión. (Si es que existe alguna.)
        '''
        self._load_session_data()
        if self.attribute_uuid:
            #Peticion POST a /LogoutServlet con los datos username y ATTRIBUTE_UUID.
            exception = 1
            try:
                response = requests.post(url=self.HOST+self.logout_endpoint, data={'username':self.user_pass['username'], 'ATTRIBUTE_UUID':self.attribute_uuid}, allow_redirects=True)
                exception = 0
            except requests.exceptions.ConnectionError:
                msg = 'Hubo un error al realizar la petición. Inténtelo de nuevo.'
            except requests.exceptions.Timeout:
                msg = 'El servidor no respondió en un tiempo dado.'
            if exception:
                print(msg) if verbose else None
                return msg if return_str else 1
            actual_time = self.get_left_time()
            self.__html(response.content, save=False) # For debugging
            self.reestablecer_variables()
            if response.text == "logoutcallback('SUCCESS');":
                self.__save_session_data()
                msg = 'Sesión cerrada con éxito. (Tiempo restante: {actual_time})'.format(actual_time=actual_time)
                print(msg) if verbose else None
                return msg if return_str else 0
            elif response.text == "logoutcallback('FAILURE');":
                self.__save_session_data()
                msg = 'Hubo un fallo al cerrar la sesión debido a datos incorrectos o a una sesión vencida.'
                print(msg) if verbose else None
                return msg if return_str else 1
            print(response.text) if verbose else None
            return response.text if return_str else 1
        else:
            msg = 'No existen los datos de la sesión.'
            print(msg) if verbose else None
            return msg if return_str else 1

    def time_that(self, time_:str, verbose=True, return_str:bool=False):
        '''Función encargada de establecer un temporizador después del cual se cerrará la sesión.
        '''
        try:
            if not self.attribute_uuid:
                msg = 'No existen los datos de la sesión.'
                print(msg) if verbose else None
                return msg if return_str else 1
            correccion = 'Ingrese una cantidad de tiempo con formato: \'hora:minuto:segundo\''
            hours, minutes, seconds = 0, 0, 0
            n_sep = time_.count(':')
            try:
                if n_sep == 2:
                    hours, minutes, seconds = [float(i) for i in time_.split(':')]
                elif n_sep == 1:
                    minutes, seconds = [float(i) for i in time_.split(':')]
                elif n_sep == 0:
                    seconds = float(time_)
                else:
                    msg = 'Formato inválido. %s'%correccion
                    print(msg) if verbose else None
                    return msg if return_str else 1
            except ValueError:
                msg = 'Datos inválidos. %s'%correccion
                print(msg) if verbose else None
                return msg if return_str else 1
            time_to_shutdown = float(hours*60**2 + minutes*60 + seconds)
            print('Waiting %0.2d:%0.2d:%0.3f'%(hours, minutes, seconds))
            try:
                for i in tqdm(range(100)):
                    sleep(time_to_shutdown/100)
            except NameError:
                total_movements = 50
                bar = ['-' for i in range(total_movements)]
                percentage = 0
                for i in range(total_movements):
                    bar[i] = '#'
                    percentage += round(1/total_movements*100)
                    print(''.join(bar) + ' %d'%percentage + '%', end='\r', flush=True)
                    sleep(time_to_shutdown/total_movements)
            print('\nCerrando sesión.')
            status = 1
            while status == 1:
                status = self.logout(return_str=return_str)
            return status
        except KeyboardInterrupt:
            msg = 'Abortando temporizador.'
            print(msg) if verbose else None
            return msg if return_str else 1

    @property
    def help(self):
        bar=''.join(['#' for i in range(50)])
        msg_list = ['config --->  Muestra la configuración establecida. (Usuario a usar en la sesión.)', 'choose --->  Permite cambiar el usuario a usar en la sesión. (Ej: -> "choose usuario@nauta.com.cu")', 'l      --->  Inicia sesión con la cuenta de ETECSA \'%s\'.'%self.config['choose'], 'lo     --->  Termina la sesión. (Si es que existe una.)', 't      --->  Intenta determinar cuanto tiempo restante le queda a la cuenta.', 'time   --->  Programa el apagado de la sesión en un tiempo especificado. (Ej: -> "time 2:3" ==> [2 minutos y 3 segundos])', 'load   --->  Intenta cargar un archivo de configuración existente.', 'h      --->  Muestra el panel de ayuda.']
        help_msg = bar+'\nPanel de ayuda:\nComando      Descripción\n%s\n\n'%'\n'.join(msg_list).strip('\n')+bar
        return help_msg
    @property
    def config_msg(self):
        data = ''
        d = {'Usuario': self.config['choose'], 'ATTRIBUTE_ID':self.attribute_uuid, 'Momento de inicio de sesión':self.session_start_time, 'Tiempo restante al momento de iniciar sesión':self.initial_left_time, 'Tipo de conexión: ':self.connection_type.capitalize() if self.connection_type else None}
        for i in d:
            data += '%s: %s\n'%(i, d[i])
        data = data.strip('\n')
        bar = ''.join(['#' for i in range(16)])
        cmsg = bar+'CONFIGURACIÓN'+bar
        config_msg = '%s\n%s\n\n%s' %(cmsg,data,''.join('#' for i in range(len(cmsg))))
        return config_msg

#################################################################### MAIN ####################################################################
def main():
    logger = EtecsaLogger()

    if len(argv) > 1:        
        arg_1 = argv[1].lower().strip('-/')
        if arg_1 == 'l':
            if len(argv) == 2:
                logger.login()
            elif len(argv) == 3:
                if argv[2].isdigit():
                    logger.login()
                    logger.time_that(argv[2])
        elif arg_1 == 'lo':
            logger.logout()
        elif arg_1 in ['t?', 'gt']:
            print(logger.get_left_time())
        elif arg_1 in ['time', 'timer', 'timethat', 'time_that', 't']:
            if not logger.attribute_uuid:
                print('No existen los datos de la sesión.')
                exit(1)
            e = input('Ingrese un tiempo a esperar: ') if len(argv) < 3 else argv[2]
            if e == 'q':
                exit(0)
            logger.time_that(e)
        elif arg_1 in ['c', 'choose', 'e', 'elegir']:
            username = input('Ingrese el usuario: ') if len(argv) < 3 else argv[2]
            if username == 'q':
                exit(0)
            logger.save_config(username)
        elif arg_1 in ['config', 'options', 'opciones']:
            print(logger.config_msg)
        elif arg_1 in ['h', 'help', '/?', '?']:
            print(logger.help)
    else:
        try:
            while True:
                entrada = input('-> ').lower().strip('-/ ')
                entrada_lista = entrada.split()
                if entrada == '':
                    continue
                elif entrada in ['l', 'login']:
                    try:
                        logger.login()
                    except requests.ConnectionError:
                        print('Error de conexión.')
                elif entrada in ['lo', 'logout']:
                    try:
                        logger.logout()
                    except requests.ConnectionError:
                        print('Error de conexión.')
                elif entrada in ['t?', 'gt']:
                    print(logger.get_left_time())
                elif entrada in ['onlinetime', 'online_time', 'ontime']:
                    print(logger.onTime())
                elif any([entrada.split()[0] == i for i in ['time', 'timer', 'timethat', 'time_that', 't']]):
                    if not logger.attribute_uuid:
                        print('No existen los datos de la sesión.')
                        continue
                    time_to_wait = False
                    res = entrada.strip().split()
                    if len(res) == 1:
                        time_to_wait = input('Ingrese un tiempo a esperar: ')
                    elif len(res) == 2:
                        time_to_wait = res[1]
                    if time_to_wait == 'q':
                        exit(0)
                    r = logger.time_that(time_to_wait) if time_to_wait else None
                    print() if r else None
                elif entrada == 'load':
                    logger._load_session_data(True)
                elif any([word in entrada for word in ['choose', 'elegir']] + [entrada.split()[0] in i for i in ['c', 'e']]):
                    username = False
                    res = entrada.split()
                    if len(res) == 1:
                        username = input('Ingrese el usuario: ')
                        if username == 'q':
                            print()
                            continue
                    elif len(res) == 2:
                        username = res[1]
                    r = logger.save_config(username) if username else None
                    print() if r else None
                elif entrada == 'config':
                    print(logger.config_msg)
                elif entrada in ['h', 'help', '/?', '?']:
                    print(logger.help)
                elif entrada in ['cls', 'clear']:
                    clear_screen()
                elif entrada in ['ping', 'p']:
                    os.system('ping 1.1.1.1 -n 1')
                    print()
                elif entrada == 'q':
                    break
                elif len(entrada_lista) == 2:
                    if (entrada_lista[0] in ['l', 'login']) and entrada_lista[1].isdigit():
                        logger.login()
                        logger.time_that(entrada_lista[1])
                else:
                    print('Comando inválido.')
        except KeyboardInterrupt:
            pass
        print('\nSaliendo...')

if __name__ == '__main__':
    main()