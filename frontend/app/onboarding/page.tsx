import OnboardingWizard from "@/components/onboarding/OnboardingWizard";

export const metadata = {
  title: "Onboarding — REDPULSE",
  description: "First-run onboarding for REDPULSE controlled pentesting",
};

export default function OnboardingPage() {
  return (
    <div className="min-h-screen bg-[var(--background)] py-8 px-4">
      <OnboardingWizard />
    </div>
  );
}
