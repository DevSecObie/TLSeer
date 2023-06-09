from flask import Flask, request, render_template, Response, make_response, redirect, url_for, flash, session, jsonify
from dotenv import load_dotenv
from flask_migrate import Migrate
import logging
import traceback
import re
import ssl
import socket
import csv
import io
import json
import secrets
import os
import requests
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename
from models import db, DomainCheckResult 
import pymysql
pymysql.install_as_MySQLdb()

app = Flask(__name__)

load_dotenv()

connection_string = os.environ.get('JAWSDB_URL') or os.environ.get('SQLALCHEMY_DATABASE_URI')

if connection_string:
    app.config['SQLALCHEMY_DATABASE_URI'] = connection_string.replace("mysql://", "mysql+pymysql://")
else:
    raise ValueError("No database URL provided. Please set the 'JAWSDB_URL' or 'SQLALCHEMY_DATABASE_URI' environment variable.")


secret_key = secrets.token_hex(16)
app.config['SECRET_KEY'] = secret_key

# Ensure the correct driver is used for MySQL
if connection_string:
    app.config['SQLALCHEMY_DATABASE_URI'] = connection_string.replace("mysql://", "mysql+pymysql://")
else:
    raise ValueError("The JAWSDB_URL environment variable is not set.")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

migrate = Migrate(app, db)



@app.route('/db') 
def database():  # Change this function name to 'database' or another appropriate name
    # Add a new record
    result = DomainCheckResult(domain='example.com', tls_version='TLSv1.3', cipher_suite='ECDHE-RSA-AES128-GCM-SHA256')
    db.session.add(result)
    db.session.commit()

    # Query all records
    results = DomainCheckResult.query.all()
    
    # Use the db.html template to render the results
    return render_template('db.html', results=results)


# logging
logging.basicConfig(filename='tls_settings.log', level=logging.INFO)

# Input validation with regular expression
def validate_domain(domain):
    domain_regex = re.compile(
        r'^(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z]{2,}$', re.IGNORECASE)
    return domain_regex.match(domain) is not None

# Additional checks
def check_hsts(domain):
    try:
        response = requests.head(f'https://{domain}', timeout=3)
        return 'strict-transport-security' in response.headers
    except Exception as e:
        logging.error(f"Error checking HSTS for {domain}: {e}")
        return False


def check_ocsp_stapling(domain):
    try:
        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_OPTIONAL
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                try:
                    ocsp_url = x509_cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value.access_descriptions[0].access_location.value
                    return ocsp_url.startswith("http://ocsp.") or ocsp_url.startswith("https://ocsp.")
                except x509.ExtensionNotFound:
                    return False
    except Exception as e:
        logging.error(f"Error checking OCSP Stapling for {domain}: {e}")
        return False

def check_certificate_transparency(sock):
    return ssl.OP_NO_TLSv1_3 in sock.context.options

def get_certificate_expiration(cert):
    expiration = cert.not_valid_after
    return expiration.replace(tzinfo=None)

results = []

@app.route('/', methods=['GET', 'POST'])
def tls():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'submit':
            # Get the domain from the request
            domain = request.form.get('domain')

            if domain and validate_domain(domain):
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((domain, 443), timeout=5) as sock:  # Adjust the timeout value here
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            tls_version = ssock.version()
                            cipher_suite = ssock.cipher()[0]

                            # New code
                            hsts = check_hsts(domain)
                            ocsp_stapling = check_ocsp_stapling(ssock)
                            cert_transparency = check_certificate_transparency(ssock)
                            cert = x509.load_der_x509_certificate(ssock.getpeercert(binary_form=True), default_backend())
                            cert_expiration = get_certificate_expiration(cert)


                            # Logging
                            logging.info(f'Domain: {domain}, TLS Version: {tls_version}, Cipher Suite: {cipher_suite}, HSTS: {hsts}, OCSP Stapling: {ocsp_stapling}, Certificate Transparency: {cert_transparency}, Certificate Expiration: {cert_expiration}')
                            results.append({'domain': domain, 'tls_version': tls_version, 'cipher_suite': cipher_suite, 'hsts': hsts, 'ocsp_stapling': ocsp_stapling, 'cert_transparency': cert_transparency, 'cert_expiration': cert_expiration})
                except ssl.SSLError as e:
                    logging.error(f'Error getting TLS settings for {domain}: {e}')
                    results.append({'domain': domain, 'error': f'Error: {e}'})
                except Exception as e:
                    logging.error(f'Unexpected error occurred for {domain}: {e}')
                    results.append({'domain': domain, 'error': f'Error: {e}'})
        elif action == 'clear':
            results.clear()
        elif action == 'delete':
            domain = request.form.get('domain')
            results[:] = [result for result in results if result['domain'] != domain]

    return render_template('index.html', results=results)

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')


@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/bulk_check', methods=['GET', 'POST'])
def bulk_check():
    results = []

    if request.method == 'POST':
        file = request.files.get('file')
        file_type = request.form.get('file_type')
        if file and (file_type == 'csv' and file.filename.endswith('.csv')) or (file_type == 'txt' and file.filename.endswith('.txt')):
            filename = secure_filename(file.filename)
            file_path = f'/tmp/{filename}'
            file.save(file_path)

            with open(file_path, 'r') as f:
                if file_type == 'csv':
                    reader = csv.reader(f)
                elif file_type == 'txt':
                    lines = f.readlines()
                    reader = [re.sub(r'^\d+\. ', '', line.strip()) for line in lines if line.strip()]
                for row in reader:
                    if file_type == 'csv':
                        domain = row[0].strip()
                    elif file_type == 'txt':
                        domain = row.strip()
                        print(f"Read domain from txt file: {domain}")

                    if domain and validate_domain(domain):
                        try:
                            context = ssl.create_default_context()
                            with socket.create_connection((domain, 443), timeout=5) as sock:
                                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                                    tls_version = ssock.version()
                                    cipher_suite = ssock.cipher()[0]

                                    # New code
                                    hsts = check_hsts(domain)
                                    ocsp_stapling = check_ocsp_stapling(ssock)
                                    cert_transparency = check_certificate_transparency(ssock)
                                    cert = x509.load_der_x509_certificate(ssock.getpeercert(binary_form=True), default_backend())
                                    cert_expiration = get_certificate_expiration(cert)

                                    results.append({'domain': domain, 'tls_version': tls_version, 'cipher_suite': cipher_suite, 'hsts': hsts, 'ocsp_stapling': ocsp_stapling, 'cert_transparency': cert_transparency, 'cert_expiration': cert_expiration})
                                    print(f"Added result for {domain}")
                        except ssl.SSLError as e:
                            results.append({'domain': domain, 'error': f'Error: {e}'})
                            print(f"Error: {e} for domain {domain}")
                        except Exception as e:
                            results.append({'domain': domain, 'error': f'Error: {e}'})
                            print(f"Error: {e} for domain {domain}")
            session['bulk_check_results'] = results
            flash('Bulk domain check completed.', 'success')
        else:
            flash(f'Invalid file. Please upload a {file_type.upper()} file with domains.', 'danger')

    print(f"Results: {results}")
    return render_template('bulk_check.html', results=results)



@app.route('/download_single')
def download_single_results():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Domain', 'TLS Version', 'Cipher Suite', 'Error', 'HSTS', 'OCSP Stapling', 'Certificate Transparency', 'Certificate Expiration'])
    for result in results:
        cw.writerow([result.get('domain'), result.get('tls_version'), result.get('cipher_suite'), result.get('error'), result.get('hsts'), result.get('ocsp_stapling'), result.get('cert_transparency'), result.get('cert_expiration')])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=results.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/download')
def download_results():
    if 'bulk_check_results' not in session:
        flash('No results available for download', 'warning')
        return redirect(url_for('bulk_check'))

    results = session['bulk_check_results']

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Domain', 'TLS Version', 'Cipher Suite', 'Error', 'HSTS', 'OCSP Stapling', 'Certificate Transparency', 'Certificate Expiration'])
    for result in results:
        cw.writerow([result.get('domain'), result.get('tls_version'), result.get('cipher_suite'), result.get('error'), result.get('hsts'), result.get('ocsp_stapling'), result.get('cert_transparency'), result.get('cert_expiration')])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=results.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exception(type(e), e, e.__traceback__)
    tb_str = ''.join(tb)
    app.logger.error("Exception occurred: %s", tb_str)
    return "An unexpected error occurred.", 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run()
