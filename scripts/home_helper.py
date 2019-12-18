from cybsec import db, app
from cybsec.models import DmcaHistory


class HomeHelper:
    def __init__(self, offender_ip, offender_mac, case_id, classification, evidence, user_id, action):
        self.offender_ip = offender_ip
        self.offender_mac = offender_mac
        self.case_id = case_id
        self.classification = classification
        self.evidence = evidence
        self.user_id = user_id
        self.action = action

    def edit_entry(self, entry_id):
        post = DmcaHistory.query.filter_by(id=entry_id).first()

        post.offender_ip = self.offender_ip
        post.offender_mac = self.offender_mac
        post.case_id = self.case_id
        post.classification = self.classification
        post.evidence = self.evidence
        post.action = self.action

        db.session.commit()
