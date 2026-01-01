# fix_legacy_training_progress.py
"""
Django management script to fix legacy/flat UserTrainingProgress data.
Wraps any flat progress data under the correct popupId for all users.
Usage:
    python manage.py shell < fix_legacy_training_progress.py
"""

from src.login.models import UserTrainingProgress
from django.contrib.auth import get_user_model

# List of all valid popup IDs (update as needed)
ALL_POPUP_IDS = [
    "drilling1",
    "drilling2",
    "drilling3",
    "safety1",
    "safety2",
    "safety3",
    "leadership1",
    "leadership2",
    "leadership3",
    "operations1",
    "operations2",
    "operations3",
    "earthworks1",
    "earthworks2",
    "earthworks3",
    "cost1",
    "cost2",
    "cost3",
    "contractor1",
    "contractor2",
    "contractor3",
    "field1",
    "field2",
    "field3",
    "mandatory_training",
]

fixed = 0
for progress in UserTrainingProgress.objects.all():
    pbp = progress.progress_by_popup
    # If not a dict, skip
    if not isinstance(pbp, dict):
        continue

    # CASE 1: The root is a flat/legacy object (not keyed by popupId)
    if any(
        k in pbp
        for k in ["gridProgressChecks", "comments", "signOffs", "progressPercentage"]
    ):
        # Try to guess popupId: if only one popup is missing, use that; else, use 'unknown_popup'
        missing = [pid for pid in ALL_POPUP_IDS if pid not in pbp]
        if len(missing) == len(ALL_POPUP_IDS) - 1:
            popup_id = missing[0]
        else:
            popup_id = "unknown_popup"
        progress.progress_by_popup = {popup_id: pbp}
        progress.save()
        print(
            f"Fixed user {progress.user.username}: wrapped flat data under '{popup_id}' (root was flat)"
        )
        fixed += 1
        continue

    # CASE 2: The root is a dict, but some values are flat/legacy objects (not keyed by popupId)
    updated = False
    new_pbp = pbp.copy()
    for key, value in pbp.items():
        if isinstance(value, dict) and any(
            k in value
            for k in [
                "gridProgressChecks",
                "comments",
                "signOffs",
                "progressPercentage",
            ]
        ):
            # This value is a flat/legacy object, wrap it under the key
            new_pbp[key] = {key: value}
            updated = True
            print(
                f"Fixed user {progress.user.username}: wrapped flat data under '{key}' (nested value was flat)"
            )
    if updated:
        progress.progress_by_popup = new_pbp
        progress.save()
        fixed += 1

print(f"Done. Fixed {fixed} legacy UserTrainingProgress records.")
