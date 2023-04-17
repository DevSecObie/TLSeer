from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class DomainCheckResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    tls_version = db.Column(db.String(255), nullable=False)
    cipher_suite = db.Column(db.String(255), nullable=False)
    hsts = db.Column(db.Boolean, nullable=False)
    ocsp_stapling = db.Column(db.Boolean, nullable=False)
    cert_transparency = db.Column(db.Boolean, nullable=False)
    cert_expiration = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<DomainCheckResult {self.domain}>'
