import os
import shutil
import logging
import pandas as pd
from tqdm import tqdm
from pathlib import Path
from mysql.connector import Error
from mysql.connector import pooling
from concurrent.futures import ThreadPoolExecutor, as_completed

import dotenv
dotenv.load_dotenv()

logging.basicConfig(level=logging.INFO, format='')

from idascript import IDA


class SqlController:
    def __init__(self, host_name, user_name, user_password, db_name, table_name, pool_size=32):
        self.__connection_pool = pooling.MySQLConnectionPool(
            pool_name="mypool",
            pool_size=pool_size,
            pool_reset_session=True,
            host=host_name,
            user=user_name,
            password=user_password,
            database=db_name
        )
        self.table_name = table_name
        self.__create_table()

    def __get_connection(self):
        return self.__connection_pool.get_connection()

    def __execute_query(self, query, data=None, commit=False):
        connection = self.__get_connection()
        cursor = connection.cursor()
        try:
            if data:
                cursor.executemany(query, data)
            else:
                cursor.execute(query)
            if commit:
                connection.commit()

            logging.debug("Query executed successfully")
        except Error as e:
            logging.debug(f"The error '{e}' occurred")
        finally:
            cursor.close()
            connection.close()

    def __create_table(self):
        query = f"""
        CREATE TABLE IF NOT EXISTS {self.table_name}_decompile (
            id INT AUTO_INCREMENT PRIMARY KEY,
            filename varchar(255),
            function_name varchar(255),
            pseudo_code TEXT,
            asm_code TEXT
        );
        """
        self.__execute_query(query)

    def insert_p_a_codes(self, filename, function_name, pseudo_code, asm_code):
        query = f"""
        INSERT INTO {self.table_name}_decompile (filename, function_name, pseudo_code, asm_code) VALUES (%s, %s, %s, %s);
        """
        data = [(f, ff, p, a) for f, ff, p, a in zip(filename, function_name, pseudo_code, asm_code)]
        self.__execute_query(query, data, commit=True)

    def get_o_codes(self):
        query = f"""
        SELECT filename, o_code FROM {self.table_name};
        """
        connection = self.__get_connection()
        return pd.read_sql(query, connection)


def read_files(path_list):
    return ((f.stem, open(f, 'r').read()) for f in path_list)


def action(obj_file_path: str):
    ida = IDA(obj_file_path, os.getenv("SCRIPT_ABS_PATH"), [])
    ida.start()
    retcode = ida.wait()

    asms = read_files([asm for asm in obj_file_path.parent.glob("*.asm")])
    pseudo = read_files([asm for asm in obj_file_path.parent.glob("*.pseudo")])

    asms = pd.DataFrame(asms).set_index(0)
    pseudo = pd.DataFrame(pseudo).set_index(0)

    functions = pd.concat([asms, pseudo], join='outer', axis=1).fillna("")
    functions['filename'] = obj_file_path.parent.stem
    functions = functions.reset_index()
    functions.columns = ["function_name", "asm_code", "pseudo_code", "filename"]
    shutil.rmtree(obj_file_path.parent)

    functions = functions.to_dict(orient='list')
    sql_controller.insert_p_a_codes(functions['filename'], functions['function_name'], functions['pseudo_code'],
                                    functions['asm_code'])


def process_row(row, temp):
    folder_name = temp / row['filename']
    folder_name.mkdir(exist_ok=True, parents=True)

    with open(folder_name / 'OBJ.o', 'wb') as f:
        f.write(row['o_code'])

    action(folder_name / 'OBJ.o')


if __name__ == "__main__":
    host_name = os.getenv("HOST_NAME")
    user_name = os.getenv("USER_NAME")
    user_password = os.getenv("USER_PASSWORD")
    db_name = os.getenv("DB_NAME")

    major = 5
    minor = 0

    sql_controller = SqlController(host_name, user_name, user_password, db_name, f"linux_{major}_{minor}")
    df = sql_controller.get_o_codes()

    temp = Path("TEMP")
    if temp.exists:
        shutil.rmtree(temp)

    temp.mkdir(exist_ok=True, parents=True)

    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(process_row, row, temp)
            for row in df.to_dict(orient='records')
        ]

        for _ in tqdm(as_completed(futures), total=len(futures)):
            pass
