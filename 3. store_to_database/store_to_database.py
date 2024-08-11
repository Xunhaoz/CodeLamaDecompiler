import logging
import os

import pandas as pd
from tqdm import tqdm
import mysql.connector
from pathlib import Path
from mysql.connector import Error
import dotenv

dotenv.load_dotenv()
logging.basicConfig(level=logging.INFO, format='')

host_name = os.getenv("HOST_NAME")
user_name = os.getenv("USER_NAME")
user_password = os.getenv("USER_PASSWORD")
db_name = os.getenv("DB_NAME")


class SqlController:
    def __init__(self, host_name, user_name, user_password, db_name, table_name, pool_size=32):
        self.__connection_pool = mysql.connector.pooling.MySQLConnectionPool(
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
        CREATE TABLE IF NOT EXISTS {self.table_name} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            code_path varchar(255),
            filename varchar(255),
            c_code TEXT,
            o_code LONGBLOB
        );
        """
        self.__execute_query(query)

    def insert_c_o_codes(self, code_path: list, filename: list, c_codes: list, o_codes: list):
        query = f"""
        INSERT INTO {self.table_name} (code_path, filename, c_code, o_code) VALUES (%s, %s, %s, %s);
        """
        data = [(p, f, c, o) for p, f, c, o in zip(code_path, filename, c_codes, o_codes)]

        # batch insert into the database
        self.__execute_query(query, data, commit=True)


# recursively find all .c and .o files in the root_path and convert them to a pandas dataframe
def rglob2df(root_path):
    all_files = list(root_path.rglob("*"))

    formated_all_files = {
        "name": [],
        "stem": [],
        "suffix": [],
        "path": [],
    }

    for id_, all_file in enumerate(all_files):
        formated_all_files["name"].append(all_file.name)
        formated_all_files["stem"].append(all_file.stem)
        formated_all_files["suffix"].append(all_file.suffix)
        formated_all_files["path"].append(str(all_file.relative_to(root_path).parent))

    df_all_files = pd.DataFrame(formated_all_files)
    o_files = df_all_files[df_all_files['suffix'] == '.o']
    c_files = df_all_files[df_all_files['suffix'] == '.c']

    oc_files = pd.merge(
        o_files, c_files, on=['stem', 'path'], how='inner'
    )[['path', 'stem', 'name_x', 'suffix_x', 'name_y', 'suffix_y']]
    return oc_files.to_dict(orient='records')


def main(root_path: str = '/linux_compile/linux/linux-5.5', table_name: str = "linux_5_5"):
    root_path = Path(root_path)
    sql_controller = SqlController(host_name, user_name, user_password, db_name, table_name)

    oc_files = rglob2df(root_path)

    for id_, row in tqdm(enumerate(oc_files), total=len(oc_files)):
        try:
            with open(root_path / row['path'] / row['name_y'], 'r') as f:
                c_code = f.read()

            with open(root_path / row['path'] / row['name_x'], 'rb') as f:
                o_code = f.read()

            sql_controller.insert_c_o_codes([row['path']], [row['stem']], [c_code], [o_code])
        except Exception as e:
            logging.error(f"Error: {e}")
            continue


if __name__ == "__main__":
    main()
