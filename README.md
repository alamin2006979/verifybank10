# Universal Verification Portal

A Flask-based admin portal for managing authorized banks/institutions and creating QR-based document verification records.

## Features
- Admin login
- Bank / institution management: name, address, website, logo, active/inactive status
- Select a bank when creating a verification record
- Bank logo/name/address automatically appear on the public QR verification page
- Currency dropdown (BDT, USD, MYR, GBP, EUR, SGD, AUD, CAD, AED, SAR)
- Calendar date pickers for report and statement dates
- Private PDF upload
- Unique verification code and QR generation
- Public verification URL
- Revoke / activate verification records
- Search by code, bank, account name or holder name
- SQLite locally or PostgreSQL through `DATABASE_URL`

## Run locally
```bash
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

Create an admin if needed:
```bash
python -m flask --app app create-admin
```

## Production
Use environment variables for `SECRET_KEY`, `BRAND_NAME`, `BRAND_SUBTITLE`, and `DATABASE_URL`. Run with `gunicorn app:app`.

For production, use persistent/object storage for uploaded PDFs and logos if the hosting platform has an ephemeral filesystem.

Only use organization names, logos, documents and records that you are authorized to publish. This portal verifies records stored in this system and is not an independent bank verification service.
