import { FindingsTable } from "@/components/FindingsTable";
import { RemediationTracker } from "@/components/RemediationTracker";
import { SeverityCounters } from "@/components/SeverityCounters";

export default function FindingsPage() {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      <div className="flex min-w-0 flex-col gap-4 xl:col-span-9">
        <SeverityCounters />
        <FindingsTable />
      </div>
      <div className="xl:col-span-3">
        <RemediationTracker className="h-[720px]" />
      </div>
    </div>
  );
}
