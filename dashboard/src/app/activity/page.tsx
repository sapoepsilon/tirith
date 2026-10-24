import { AiTimeline } from "@/components/AiTimeline";
import { EventFeed } from "@/components/EventFeed";
import { Topology } from "@/components/Topology";

export default function ActivityPage() {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      <div className="flex min-w-0 flex-col gap-4 xl:col-span-7">
        <EventFeed className="h-[calc(100vh-110px)] min-h-[600px]" limit={400} />
      </div>
      <div className="flex min-w-0 flex-col gap-4 xl:col-span-5">
        <AiTimeline className="h-[460px]" limit={40} />
        <Topology height={360} />
      </div>
    </div>
  );
}
