-- The AI Gateway Dynamic Route a run was sent through, or NULL for normal
-- routing. Added because a route CHOOSES THE MODEL: two runs on the same
-- corpus, same gateway and same settings are still not comparable if one went
-- through a route and the other did not, and without this column they look
-- identical in the run list. `model` records what ran, but not why.
ALTER TABLE redteam_runs ADD COLUMN dynamic_route TEXT;
