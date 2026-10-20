import { Component, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Notice } from "./common";

/** 某个页面渲染出错时只影响这一块，并给出重试按钮，不让整个页面白屏。 */
export class Boundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Notice kind="bad">
        页面出错了：{this.state.error.message}
        <div className="mt-2">
          <Button size="sm" variant="outline" onClick={() => this.setState({ error: null })}>
            重试
          </Button>
        </div>
      </Notice>
    );
  }
}
