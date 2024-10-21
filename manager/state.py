current_alert: dict = {}

async def update(alert: dict):
    # TLDR: check MITRE IDs, see which attacks have taken place, see
    # which preconditions have taken place, update DB based on it.
    global current_alert
    current_alert = alert


async def mitigations_needed() -> bool:
    # TLDR: check if based on the current state the probability of
    # going to the next state is high, combine it with the cost of
    # incurring the next state, combine it with the risk score(?), and
    # evaluate against the configured risk threshold.
    return True


async def get_mitigation_preconditions() -> dict:
    # TLDR: based on the current state, get a series of preconditions
    # to feed to the solver.
    global current_alert
    return {
        'mitre_id': current_alert['rule']['id']
    }


async def get_workflows() -> list[dict]:
    return [
        {
            'name': 'delete_file',
            'webhook': '6b219a4d-9723-4607-b6c6-6e56f790650c',
            'attacks': ['T1222.002', 'T1204.002']
        },
        {
            'name': 'close_conn',
            'webhook': 'aa2e31ea-dd3e-4471-ad4e-3f032bdb381d',
            'attacks': ['T1041', 'T1219']
        },
        {
            'name': 'handle_ransomware',
            'webhook': '1d5366eb-8006-45a3-8fff-e764c283b811',
            'attacks': ['T1204.002']
        }
    ]
