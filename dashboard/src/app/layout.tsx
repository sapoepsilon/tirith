import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "@xyflow/react/dist/style.css";
import "./globals.css";
import { Shell } from "@/components/Shell";

const inter = Inter({ variable: "--font-inter", subsets: ["latin"] });
const mono = JetBrains_Mono({ variable: "--font-jbmono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Tirith · Security Command Center",
  description: "AI security assessment and remediation — live posture, findings, validation and fixes.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${inter.variable} ${mono.variable} antialiased`}>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
