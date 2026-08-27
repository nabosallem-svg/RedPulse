import { redirect } from "next/navigation";

export default async function FindingsRedirect({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  redirect(`/dashboard/engagements/${id}`);
}
