import { AiTimeline } from "@/components/AiTimeline";
import { EventFeed } from "@/components/EventFeed";
import { FindingsTable } from "@/components/FindingsTable";
import { PostureGauge } from "@/components/PostureGauge";
import { RemediationTracker } from "@/components/RemediationTracker";
import { SeverityCounters } from "@/components/SeverityCounters";
import { TopActions } from "@/components/TopActions";
import { Topology } from "@/components/Topology";

export default function Overview() {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      <div className="flex min-w-0 flex-col gap-4 xl:col-span-8">
        <TopActions />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-[300px_1fr]">
          <PostureGauge />
          <SeverityCounters />
        </div>
        <Topology height={430} />
        <FindingsTable limit={8} />
      </div>
      <div className="flex min-w-0 flex-col gap-4 xl:col-span-4">
        <EventFeed className="h-[520px]" />
        <AiTimeline className="h-[360px]" />
        <RemediationTracker className="h-[420px]" />
      </div>
    </div>
  );
}
