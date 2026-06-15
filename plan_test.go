package license

import "testing"

func TestPlanConstants(t *testing.T) {
	for p, want := range map[Plan]string{
		PlanStandard:   "standard",
		PlanPro:        "pro",
		PlanEnterprise: "enterprise",
	} {
		if string(p) != want {
			t.Errorf("plan %q != %q", string(p), want)
		}
	}
}
