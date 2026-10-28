# Bind this local tag to the already tested reference image ID before building.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER 0:0
ARG BUILD_ASSESSMENT_SHA256
RUN --network=none \
    --mount=type=bind,source=inputs,target=/package-candidate \
    --mount=type=bind,source=helpers,target=/package-trial \
    OPENID_NCURSES_TRIAL=1 \
    OPENID_CANDIDATE_ASSESSMENT_SHA256="$BUILD_ASSESSMENT_SHA256" \
    python /package-trial/trial_install.py
USER 10001:10001
LABEL io.openid.candidate-only="true" io.openid.evaluation="ncurses"
