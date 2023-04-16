from dotenv import load_dotenv
import pandas as pd
from sqlalchemy import create_engine
import OS

load_dotenv()

connection_string = os.getenv('DB_CONNECTION')

