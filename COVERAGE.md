# Incident coverage

The map covers meaningful publicly reported cyber incidents worldwide, including AI-related incidents and conventional attacks on essential services, organizations and supply chains. It is a reporting collection, not a count of every attack that occurred.

## Inclusion

Include substantiated compromises with meaningful operational, sensitive-data, financial, safety or downstream consequences. A single regional hospital or utility can qualify. Do not require a specific loss figure, 100,000 victims, a nationwide outage or AI involvement. Separate confirmation of an incident from uncertainty about its cause, attribution and final impact.

Exclude petty isolated theft, blocked attempts, routine scanning, vulnerabilities without actual exploitation, speculative predictions, product announcements and research demonstrations without real external harm. Defer potentially meaningful reports when evidence is inadequate. Accidental exposure alone is not automatically a confirmed attack.

## Collection

- Eight news, healthcare, research and government feeds, plus the existing AI incident tracker.
- Public SecurityWeek and HIPAA Journal RSS archives are traversed back 90 days. Failed pages retain their cursor for retry. Archives are revisited weekly.
- `backfill_sources.json` contains short, sourced research leads for verified omissions. These are evidence for model review, not automatically approved incidents.
- Full feed content is preferred; otherwise readable article text is fetched with bounded timeouts and size. When retrieval fails, the decision records that only a summary was available.
- Reports containing several distinct incidents can produce several records. Same-event reports are merged as sources. Preserve attribution and geographic uncertainty.
- `pending.json` retains unprocessed candidates and a short feed excerpt across runs. Fresh reports are reviewed before older queued work. Runs checkpoint and stop processing after 35 minutes, leaving time to publish the queue before the job timeout. `decisions.json` stores inclusion, exclusion and deferral reasons, source URLs and retrieval quality, without full article bodies or credentials.
- Changed feed evidence is re-screened. Deferred reports are eligible for review after two days; other reports after seven days, within the 90-day reporting window, including articles no longer in feeds.
- Explicitly reviewed exclusions remain excluded until fresh feed evidence changes; the audit records the review reason.
- `feed_status.json` records source health, errors, queue size and last successful collection. Authentication failures stop processing and fail the workflow. Partial source coverage is visibly labeled.

## Dates and geography

`date` is the incident/disclosure date extracted from the report. `reported_date` and `last_reported` retain publication dates independently. The 7-day and 30-day controls use latest reporting; old incidents with substantive new disclosures can therefore appear without being described as new attacks.

Pins represent supported victim locations or explicitly labeled, sourced vendor headquarters fallbacks. A campaign may have multiple pins. The global panel contains incidents without a supported geographic anchor. Neither clusters nor that panel are national/worldwide attack totals.

## Maintenance

Run `python -m unittest test_selection test_coverage test_site` before deployment. The scheduled workflow runs every six hours; GitHub may delay schedules. Article/model failures remain retryable. Check both Actions and `feed_status.json`, rather than relying on a green workflow badge alone.

Pages deploys explicitly after every updater completion (including failed collections, to show their health) and normal pushes to `main`. The deployment checks out the latest committed data and embeds its actual Git revision for client refresh detection. This avoids relying on a bot commit to trigger a branch-based Pages build, which GitHub does not support.

The initial backfill searches a 90-day publication window; it cannot establish exhaustive worldwide coverage. Publishers can block article retrieval, disclose incidents late, omit locations, or revise reports. Review decisions and add reliable sources when a meaningful incident is missed.
