import { redirect } from "next/navigation";

/** The overview is the front door; signed-out visitors are sent to sign in by the app shell. */
export default function Home() {
  redirect("/overview");
}
