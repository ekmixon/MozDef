from .alerttask import AlertTask


class DeadmanAlertTask(AlertTask):

    def executeSearchEventsSimple(self):
        return self.main_query.execute(self.es, indices=self.event_indices, size=1)
