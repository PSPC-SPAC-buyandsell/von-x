from app import app, settings
from app.services.claims import init_claim_handler

init_claim_handler(app)

if __name__ == '__main__':
    app.run()
