from manager import state, workflows


async def find_workflow() -> dict:
    # TLDR: obtain mitigation preconditions, feed them to the solver,
    # translate the results to a specific mitigation description dict
    # and return that.
    mappings: list[tuple[str, list[str]]] = [
        ('100002', ['T1041', 'T1219']),
        ('100003', ['T1222.002']),
        ('100004', ['T1204.002']),
    ]
    preconditions = await state.get_mitigation_preconditions()
    attacks = []

    # Transform Wazuh rule ID into MITRE ATT&CK ID/s
    for r, a in mappings:
        if preconditions['mitre_id'] == r:
            attacks = a
            break

    if len(attacks) == 0:
        return {}

    # Find the first workflow that can mitigate *all* of the attacks
    # TODO: if none can, run two workflows that get the same thing
    # done.
    for workflow in await workflows.get():
        if all(id in workflow['attacks'] for id in attacks):
            return workflow

    # Thought: if in the future we filter out the workflows we
    # retrieve from the db, we should restrict them to "can solve at
    # least one of these attacks".  Then we could either sort them by
    # least amount of attacks that it can mitigate (very precise
    # mitigations, will probably have lower cost) or we could find
    # workflows that mitigate both of them and with the lowest cost.
    # Or, you know, we could give it to the solver and have it figure
    # it all out.

    return {}
