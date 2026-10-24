import { AnalystPanel } from "@/components/AnalystPanel";
import { EventFeed } from "@/components/EventFeed";

export default function AnalystPage() {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      <div className="flex min-w-0 flex-col gap-4 xl:col-span-8">
        <AnalystPanel height={720} />
      </div>
      <div className="xl:col-span-4">
        <EventFeed className="h-[calc(100vh-110px)] min-h-[600px]" limit={200} />
      </div>
    </div>
  );
}