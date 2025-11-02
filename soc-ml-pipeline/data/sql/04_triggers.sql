CREATE TRIGGER protect_alerts_mat_delete
BEFORE DELETE ON alerts_enriched_mat
BEGIN
  SELECT RAISE(ABORT, 'Deletion not allowed on alerts_enriched_mat');
END;
CREATE TRIGGER trg_brf_ins AFTER INSERT ON wz_scores_brf
BEGIN
  UPDATE wz_scores_brf SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_brf_risk_to_score_ins
AFTER INSERT ON wz_scores_brf
BEGIN
  UPDATE wz_scores_brf
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_brf_risk_to_score_upd
AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_brf
BEGIN
  UPDATE wz_scores_brf
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_brf_upd AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_brf
BEGIN
  UPDATE wz_scores_brf SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_if_ins AFTER INSERT ON wz_scores_if
BEGIN
  UPDATE wz_scores_if SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_if_risk_to_score_ins
AFTER INSERT ON wz_scores_if
BEGIN
  UPDATE wz_scores_if
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_if_risk_to_score_upd
AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_if
BEGIN
  UPDATE wz_scores_if
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_if_upd AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_if
BEGIN
  UPDATE wz_scores_if SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_rf_ins AFTER INSERT ON wz_scores_rf
BEGIN
  UPDATE wz_scores_rf SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
CREATE TRIGGER trg_rf_risk_to_score_ins
AFTER INSERT ON wz_scores_rf
BEGIN
  UPDATE wz_scores_rf
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_rf_risk_to_score_upd
AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_rf
BEGIN
  UPDATE wz_scores_rf
     SET score  = NEW.risk_score,
         bucket = NEW.risk_bucket
   WHERE id = NEW.id;
END;
CREATE TRIGGER trg_rf_upd AFTER UPDATE OF risk_score, risk_bucket ON wz_scores_rf
BEGIN
  UPDATE wz_scores_rf SET score=NEW.risk_score, bucket=NEW.risk_bucket WHERE id=NEW.id;
END;
