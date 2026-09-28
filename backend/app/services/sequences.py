from pymongo import ReturnDocument
from ..database import get_db


def next_sequence(name, floor=0):
    """Atomically returns the next value of a named counter in `job_sequences`.

    `floor` lifts a fresh counter past IDs that already exist (e.g. records created
    before counters were introduced), so the first value issued is at least floor+1.
    """
    col = get_db()['job_sequences']
    if floor:
        col.update_one({'_id': name}, {'$max': {'value': int(floor)}}, upsert=True)
    doc = col.find_one_and_update(
        {'_id': name}, {'$inc': {'value': 1}}, upsert=True, return_document=ReturnDocument.AFTER
    )
    return int(doc['value'])
