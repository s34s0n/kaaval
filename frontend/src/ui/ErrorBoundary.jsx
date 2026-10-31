// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { Component } from "react";

// A render error shows a small inline panel instead of a blank screen.
export default class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  componentDidCatch(err, info) { console.error("Kaaval UI error:", err, info); }
  render() {
    if (this.state.err) {
      return (
        <div className="h-full flex items-center justify-center bg-bg text-text p-8">
          <div className="panel p-4 max-w-lg">
            <div className="text-crit text-sm font-semibold mb-1">UI error</div>
            <div className="text-xs text-muted mb-3">A view failed to render. The backend and detection are unaffected.</div>
            <pre className="text-2xs mono text-muted whitespace-pre-wrap max-h-40 overflow-auto">{String(this.state.err)}</pre>
            <button onClick={() => this.setState({ err: null })}
              className="mt-3 h-7 px-3 text-2xs border border-accent/60 text-accent hover:bg-accent/10">Retry</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
