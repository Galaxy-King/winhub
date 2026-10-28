"""Optional real PostgreSQL, independent-process occurrence claim regression."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from flask import Flask
import sqlalchemy as sa

from core.database import db, ScheduledTask, ScheduleRun
from core.scheduling import normalize_spec, normalize_policy


@unittest.skipUnless(os.environ.get('WINHUB_SCHEDULER_TEST_PG'), 'Requires isolated PostgreSQL test database')
class PostgreSQLClaimTests(unittest.TestCase):
    def test_workers_cannot_double_dispatch_automatic_or_queued_occurrences(self):
        uri = os.environ['WINHUB_SCHEDULER_TEST_PG']
        schema = 'scheduler_test_' + uuid.uuid4().hex
        engine = sa.create_engine(uri)
        with engine.begin() as connection:
            connection.execute(sa.schema.CreateSchema(schema))
        app = Flask(__name__)
        app.config.update(SQLALCHEMY_DATABASE_URI=uri, SQLALCHEMY_TRACK_MODIFICATIONS=False,
                          SQLALCHEMY_ENGINE_OPTIONS={'connect_args': {'options': '-csearch_path=' + schema}})
        db.init_app(app)
        worker = '''
import json, os, sys, time
from datetime import datetime
from flask import Flask
from core.database import db
from core.scheduling import run_schedule
app = Flask(__name__)
app.config.update(SQLALCHEMY_DATABASE_URI=os.environ['WINHUB_SCHEDULER_TEST_PG'], SQLALCHEMY_ENGINE_OPTIONS={'connect_args':{'options':'-csearch_path='+sys.argv[1]}})
db.init_app(app)
def dispatch(*args, **kwargs):
    time.sleep(.15)
    return {'success':False, 'message':'isolated dispatch fixture'}
with app.app_context():
    kwargs = {'queued_run_id':sys.argv[3]} if sys.argv[3] != '-' else {'due_at':datetime.fromisoformat(sys.argv[4])}
    print(json.dumps(run_schedule(sys.argv[2],dispatch,**kwargs)))
'''
        try:
            with app.app_context():
                db.create_all()
                due = datetime.utcnow() - timedelta(minutes=1)
                schedule = ScheduledTask(name='Concurrent fixture', cron_expr='CALENDAR', next_run_at=due,
                    schedule_spec=json.dumps(normalize_spec(dict(kind='daily', timezone='UTC', start='2026-01-01T03:00', every=1))),
                    execution_policy=json.dumps(normalize_policy({'overlap':'queue_one'})), is_active=True)
                db.session.add(schedule)
                db.session.commit()
                schedule_id = schedule.id

                def pair(queued_id='-'):
                    command = [sys.executable, '-c', worker, schema, schedule_id, queued_id, due.isoformat()]
                    def execute(_):
                        result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        return json.loads(result.stdout.splitlines()[-1])
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        return list(pool.map(execute, range(2)))

                pair()
                db.session.expire_all()
                self.assertEqual(ScheduleRun.query.count(), 1)
                self.assertEqual(ScheduleRun.query.one().status, 'DispatchFailed')
                queued = ScheduleRun(schedule_id=schedule_id, occurrence_key='queued-fixture', name='Queued fixture',
                    category='Test', source='scheduler', scheduled_at=due, status='Queued', policy_snapshot='{}')
                db.session.add(queued)
                db.session.commit()
                pair(queued.id)
                db.session.expire_all()
                self.assertEqual(db.session.get(ScheduleRun, queued.id).status, 'DispatchFailed')
                self.assertEqual(ScheduleRun.query.count(), 2)
                db.session.remove()
                db.engine.dispose()
        finally:
            with engine.begin() as connection:
                connection.execute(sa.schema.DropSchema(schema, cascade=True))
            engine.dispose()
