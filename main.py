import re
import html
import json
import time
import requests

from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class Tracer():
    """A class for transferring data to a new SIEM version
    """
    
    __authorize_page = ":3334/account/login?returnUrl=/#/authorization/landing"

    def __init__(self, hostname, login, 
                 password, auth_type=0):
        """Initializing a platform instance

        Args:
            hostname  (str): like 127.0.0.1 or example.com
            login     (str): account name in ptmc or domain
            password  (str): password for this account
            auth_type (int): 0 - PT KB, 1 - LDAP
        Return:
            None
        """

        self.__session = requests.Session()
        self.__folders = list()
        self.__filters = list()
        self.__url = f"https://{hostname}"
        self.__auth = {
            "authType": auth_type, 
            "username": login, 
            "password": password, 
            "newPassword": None
        }
        print(f"[X] Добавлена новая площадка - {hostname}!")


    def connect(self) -> bool:
        """Creating a new authorized
        session for initialized site.

        Returns:
            bool
                returns True if authorization
                was successfull, else returns False
        """
        print(f"[X] Выполняю попытку получить " \
              f"авторизацию на узле {self.__auth.get('url')}..")

        with requests.Session() as session:
            try:
                pre_auth = session.get(
                    f"{self.__url}{self.__authorize_page}", 
                    verify=False
                )

                auth = session.post(
                    f"{self.__url}:3334/ui/login/", 
                    json=self.__auth,
                    verify=False
                )

                if auth.status_code != 200:
                    print(f"[X] Не удалось подключиться, статус ошибки:\n" \
                          f"{auth.text}")
                    return False

                page = session.get(
                    f"{self.__url}/account/login?returnUrl=/#/authorization/landing",
                    verify=False
                )

                page_creds = self.core_parse_form(page.text)
                portal = session.post(page_creds[0], data=page_creds[1])
            
            except Exception as e:
                print(f"[X] Произошла ошибка при попытке получить " \
                      f"авторизацию на узле {self.__auth.get('url')}!", e)
                return False

            else:
                # Save a session
                print(f"[X] Авторизация на площадке прошла успешно! Сессия сохранена.")
                self.__session = session
                return True
    

    def get_folder_filters(self, main_folder=None):
        """Creating a hierarchy of folders and filters

        Args:
            main_folder (str):
        Returns:
            self.__filters, self.__folders
        """
        hierarchy = self.__session.get(
            f"{self.__url}/api/v2/events/filters_hierarchy",
            verify=False
        )

        if hierarchy.status_code != 200:
            print(f"[X] Не удалось получить иерархию папок и фильтров!")
            return
        
        self.__folders = []
        self.__filters = []

        hierarchy = hierarchy.json()

        for x in hierarchy.get("roots"):
            if x.get("name") == "Общие фильтры":
                self.__iter_folders(x.get("children"))
        
        print(f"[X] Сканирование завершено!")
        print(self.__folders)
                                

    def get_folder_id(self, folder_name, in_folder=None): # Дописать для любого уровня вложенности
        """Return the Id of the folder

        Args:
            folder_name (str): Name of the folder. Returns her ID
        """
        
        hierarchy = self.__session.get(
            url=f"{self.__url}/api/v2/events/filters_hierarchy",
            verify=False
        )

        if hierarchy.status_code != 200:
            print(f"[X] Не удалось получить иерархию папок!")
            return

        hierarchy = hierarchy.json()

        for x in hierarchy.get("roots"):
            if x.get("name") == "Общие фильтры":
                for folder in x.get("children"):
                    if not in_folder:
                        if folder.get("name") == folder_name:
                            return folder.get("id")
                
                    elif folder.get("name") == in_folder:
                        for f in folder.get("children"):
                            if f.get("name") == folder_name:
                                return f.get("id")
        
        return None


    def get_filter(self, uid):
        """Returns a JSON-ojbect by filter-UID
        """
        data = self.__session.get(
            url=f"{self.__url}/api/v2/events/filters/{uid}",
            verify=False
        )

        if data.status_code != 200:
            f"[X] Не удалось получить информацию по фильтру {uid}"
            return False
        
        return data.json()

        
    def restore_structure(self, main_folder, folders, filters) -> None:
        """Restore a folders and filters struct

        Args:
            main_folder (str): Name of the folder to which replication will take place
            folders     (list): List of folders obtained using 'get_folder_filters' function
            filters     (list): List of filters obtained using 'get_folder_filters' function
        """

        new_folders_uids = list() # Store a UID of new folders

        # Get a destination folder UID to replicate
        main_uid = self.get_folder_id(main_folder)

        if main_uid is None:
            f"[X] Не удалось найти папку с именем {main_folder}"
            return

        print(f"[X] Папка {main_folder} найдена! Выполняю процедуру репликации..")
        
        for x in folders:
            parentId, parentName = main_uid, x[0]

            if parentName != "Общие фильтры":
                parentId = self.get_folder_id(parentName)

                if not parentId:
                    for nf in new_folders_uids:
                        if nf[0] == parentName:
                            parentId = nf[1]
                    
                    if not parentId:
                        print(f"[X] Не найден parentId для папки {parentName}!")
                        #raise
                    
            json_data = {"parentId": parentId, "name": x[1]}
            
            print(f"[X] Создаю папку {x[1]} в {x[0]} с uid {[parentId]}")
            req = self.__session.post(
                url=f"{self.__url}/api/v2/events/folders",
                json=json_data,
                verify=False
            )
            if req.status_code != 200:
                print(f"[X] Не удалось создать папку {x[1]}!\nПричина: {req.text}")
                continue
            else:
                print(f"[X] Папка {x[1]} успешно создана!")

                res = req.json()
                new_folders_uids.append((x[1], req.json()))
                new_folders_uids.append((x[1], res.get("folderId")))
                
                for j in filters:
                    if j[0] == x[1]:
                        data = j[1]
                        data["folderId"] = res.get("folderId")
                        req = self.__session.post(
                            url=f"{self.__url}/api/v2/events/filters/",
                            json=data,
                            verify=False
                        )
                        if req.status_code != 200:
                            print(f"[X] Не удалось создать фильтр {j[0]} в папке {x[1]} - {req.text}")
                            continue
                        else:
                            print(f"[X] Фильтр {j[0]} успешно создан!")
                        
                    time.sleep(1)

            time.sleep(2)


    def __iter_folders(self, struct, depth=1, current_folder="Общие фильтры"):
        """Recursive search for filters and folders

        Args:
            struct (list): Hierarchy object
        Returns:
            None
        """

        if isinstance(struct, list):
            for x in struct:
                if x.get("type") == "folder_node":
                    print(" "*depth + f"└ {x.get('name')} в папке {current_folder}")
                    self.__folders.append((current_folder, x.get("name")))
                    self.__iter_folders(x.get("children"), depth+1, x.get("name"))
                else:
                    print(" "*depth + f"- {x.get('name')} в папке {current_folder}")
                    data = self.get_filter(x.get("id"))
                    self.__filters.append((current_folder, data))

        else:
            print(f"[X] Else")
            if struct.get("type") != "folder_node":
                print(f"[X] Найден фильтр: {struct.get('name')}")
                self.__filters.append((struct.get("name"), struct.get("id")))
                return


    def core_parse_form(self, data):
        return re.search('action=[\'"]([^\'"]*)[\'"]', data).groups()[0], {
            item.groups()[0]: html.unescape(item.groups()[1])
            for item in re.finditer(
                'name=[\'"]([^\'"]*)[\'"] value=[\'"]([^\'"]*)[\'"]',
                data
            )
        }

    # - - - Getters / Setters - - -
    def get_folders(self):
        return self.__folders
    
    def get_filters(self):
        return self.__filters


if __name__ == "__main__":
    hostname = input(f"[X] Введите адрес площадки-донора (например, 127.0.0.1 или siem.com):\n> ")
    auth = int(input(f"[X] Укажите тип входа (0 - PT MC, 1 - LDAP):\n> "))
    login = input(f"[X] Введите имя пользователя:\n> ")
    password = input(f"[X] Введите пароль пользователя:\n> ")

    worker = Tracer(hostname, login, password, auth)
    worker.connect()
    worker.get_folder_filters()

    hostname = input(f"[X] Пожалуйста, введите адрес площадки, в которую необходимо реплицировать сохраненные объекты:\n> ")
    auth = int(input(f"[X] Укажите тип входа (0 - PT MC, 1 - LDAP):\n> "))
    login = input(f"[X] Введите имя пользователя:\n> ")
    password = input(f"[X] Введите пароль пользователя:\n> ")

    replicate = Tracer(hostname, login, password, auth)
    replicate.connect()

    main_folder = input(f"[X] Пожалуйста, укажите название папки, в которую необходимо реплицировать объекты (например, Общие фильтры)\nP.S. без кавычек, как есть:\n> ")

    replicate.restore_structure(main_folder=main_folder, filters=worker.get_filters(), folders=worker.get_folders())

    print("[X] Репликация завершена!")

