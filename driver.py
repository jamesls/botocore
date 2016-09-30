"""Driver example for insight project.

Will send data to dynamodb at a constant rate.

"""
import sys
import time
import argparse

import botocore.session
from botocore import insight


TABLE_NAME = 'InsightDemo'


def seed_data(ddb):
    for i in range(100):
        ddb.put_item(TableName=TABLE_NAME,
                     Item={'Counter': {'S': str(i)}})


def get_data(ddb, rate=1):
    # Send get_item requests at a rate of `rate` items per second.
    sleep_time = 1 / float(rate)
    while True:
        ddb.get_item(TableName=TABLE_NAME, Key={'Counter': {'S': '1'}})
        #sys.stdout.write('.')
        #sys.stdout.flush()
        time.sleep(sleep_time)


def one_shot(ddb):
    ddb.get_item(TableName=TABLE_NAME, Key={'Counter': {'S': '1'}})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seed', action='store_true',
                        help='Seed ddb table with initial data.')
    parser.add_argument('--one-shot', action='store_true',
                        help='Make a single GetItem request.')
    args = parser.parse_args()
    s = botocore.session.get_session()
    insight.register_session(s)
    ddb = s.create_client('dynamodb')
    if args.seed:
        print("Seeding table with data.")
        seed_data(ddb)
        print("Done seeding table.")
    elif args.one_shot:
        one_shot(ddb)
    else:
        get_data(ddb)


if __name__ == '__main__':
    main()
