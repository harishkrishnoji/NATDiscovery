import sqlite3


class WriteToDB:
    def __init__(self, env) -> None:
        self.db = f"{env}_nat.db"
        self.conn = sqlite3.connect(self.db)
        self.c = self.conn.cursor()
        self.table = "nat"
        # self.query_insert = f'INSERT INTO {self.table} {self.columns} VALUES {self.placeholders}'
        self.create()

    def create(self):
        # Drop TABLE if exists
        self.c.execute(f'DROP TABLE IF EXISTS {self.table}')
        # Create TABLE
        self.c.execute(f"""CREATE TABLE IF NOT EXISTS {self.table} (
                        Firewall text,
                        FirewallName text,
                        Name text,
                        OriginalDestination text,
                        OriginalSource text,
                        Method text,
                        TranslatedDestination text,
                        TranslatedSource text
                        )""")
        self.conn.commit()

    def display(self):
        self.c.execute(f"SELECT * FROM {self.table}")
        [print(data) for data in self.c.fetchall()]

    def insert_row(self, document):
        self.columns = ', '.join(document.keys())
        self.placeholders = ':'+', :'.join(document.keys())
        self.query_insert = 'INSERT INTO %s (%s) VALUES (%s)' % (self.table, self.columns, self.placeholders)
        self.c.execute(self.query_insert, document)
        self.conn.commit()
