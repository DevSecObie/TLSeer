from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class DomainCheckResult(db.Model):
    __tablename__ = 'domain_check_result'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    tls_version = db.Column(db.String(255), nullable=False)
    cipher_suite = db.Column(db.String(255), nullable=False)
    hsts = db.Column(db.Boolean, nullable=True, default=False)
    ocsp_stapling = db.Column(db.Boolean, nullable=False, default=False)
    cert_transparency = db.Column(db.Boolean, nullable=False, default=False)
    cert_expiration = db.Column(db.DateTime, nullable=True, default=None)

    def __repr__(self):
        return f'<DomainCheckResult {self.domain}>'
