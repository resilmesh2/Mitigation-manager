from sanic import Config, Sanic
from sanic.log import logger

version = '1.0.0'
log = logger
ENV: Config | None = None

# The maximum number of conditions an attack graph is expected to
# have.
MAX_CONDITIONS = 100

# The rate of "interest": lower values means attack graph nodes won't
# be given high probabilities until the end, while higher values will
# asign linearly increasing probabilities.
GRAPH_INTEREST = 0.5

# The maximum impact ease of attack graph completion can have in the
# final probability score calculation.
EASE_IMPACT = 0.3

# The minimum change in probability for the database to update.
PROBABILITY_EPSILON = 0.0001

# The minimum probability for a future node to be considered as
# "requires mitigation".
PROBABILITY_TRESHOLD = 0.75


def set_config(app: Sanic):
    global ENV
    ENV = app.config


def update_config(env: dict):
    global ENV
    if ENV is None:
        ENV = Config()
    ENV.update_config(env)


def getenv(key: str, optional: bool = False) -> str:
    global ENV
    if ENV is None:
        msg = 'Environment was not initialized'
        raise ValueError(msg)
    var = ENV[key]
    if (var is None or var == '') and not optional:
        msg = f'Missing environment variable "{key}"'
        raise ValueError(msg)
    return var
