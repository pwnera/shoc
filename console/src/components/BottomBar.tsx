/**
 * The phone's bottom bar (under 768px): Overview with the inbox count, Cases,
 * Findings, Search and Ask, which opens the crew chat (its floating launcher
 * would sit over the rows). It turns into Reject | Approve while a case page
 * with a pending approval binds `case.approve`; each button runs the page's
 * own handler and confirm, and the launcher floats again. ApprovalDialog is
 * modal, so it carries the same pair in its own sheet.
 */
import { NavLink } from "react-router-dom";
import { Box, Gauge, Radar, Search } from "lucide-react";
import { toggleChat, useChatState } from "@/lib/chat";
import { runCommand, useBound } from "@/lib/commands";
import { useNeedsYou } from "@/lib/needs";
import { Button } from "./ui/button";

const PAIRS = [["case.approve", "case.reject"]] as const;

export function BottomBar({ onSearch }: { onSearch: () => void }) {
  const { count } = useNeedsYou();
  const chat = useChatState();
  const bound = new Set(useBound().map((c) => c.id));
  const pair = PAIRS.find(([approve]) => bound.has(approve));

  if (pair)
    return (
      <div className="sh-bottombar sh-bottombar--decide" role="toolbar" aria-label="Decide">
        <Button onClick={() => runCommand(pair[1])}>Reject</Button>
        <Button variant="primary" onClick={() => runCommand(pair[0])}>
          Approve
        </Button>
      </div>
    );

  return (
    <nav className="sh-bottombar sh-bottombar--tabs" aria-label="Main">
      <NavLink to="/" end className="sh-bottombar__item">
        <Gauge aria-hidden />
        <span>
          Overview{count > 0 ? <span className="sh-bottombar__count"> {count}</span> : null}
        </span>
      </NavLink>
      <NavLink to="/cases" className="sh-bottombar__item">
        <Box aria-hidden />
        <span>Cases</span>
      </NavLink>
      <NavLink to="/findings" className="sh-bottombar__item">
        <Radar aria-hidden />
        <span>Findings</span>
      </NavLink>
      <button type="button" className="sh-bottombar__item" onClick={onSearch}>
        <Search aria-hidden />
        <span>Search</span>
      </button>
      <button
        type="button"
        className="sh-bottombar__item sh-bottombar__ask"
        onClick={toggleChat}
        aria-pressed={chat.open}
        aria-label={chat.unread ? "Ask the crew, new answer" : "Ask the crew"}
        data-unread={chat.unread ? "" : undefined}
      >
        <b aria-hidden>›</b>
        <span aria-hidden>Ask</span>
      </button>
    </nav>
  );
}
