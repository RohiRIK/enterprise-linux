# Strong MDM support

**Status: design / stub only. No live Intune, Jamf, or other MDM connector claimed.**

See `docs/ARCHITECTURE.md` §5.3 and §8.

## Target story

Enroll into org MDM (Intune-class and/or Jamf-class Linux management — vendors TBD with Rohi): policy, inventory, and remote actions the platform allows.

## Day-1 design obligations (hooks)

Image and first-boot should leave clean surfaces so MDM is not a retrofit:

- Agent install slot(s)
- Device identity / facts for inventory
- Compliance-related facts
- Update / reboot policy surfaces aligned with locked auto-updates

## Not claimed today

- Shipping connector, portal, or “works with Intune/Jamf” badge
- That we are an MDM vendor replacing Intune/Jamf

## Next

Rohi names must-have vendor(s) or “hooks only” for MVP → follow-on ADR → then SHIP.
