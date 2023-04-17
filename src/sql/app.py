from models import DomainCheckResult
from dotenv import load_dotenv
import pandas as pd
from sqlalchemy import create_engine
import OS

load_dotenv()

connection_string = os.getenv('DB_CONNECTION')

app = Flask(__name__)
secret_key = secrets.token_hex(16)
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = connection_string