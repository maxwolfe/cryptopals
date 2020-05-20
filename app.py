import connexion

API_DIR = './'
API_FILE = 'swagger.yaml'
PORT = 8080

app = connexion.FlaskApp(
        __name__,
        specification_dir=API_DIR,
)
app.add_api(API_FILE)

if __name__ == '__main__':
    app.run(port=PORT)
