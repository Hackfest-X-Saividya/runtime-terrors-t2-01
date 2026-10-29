import { Component, type ErrorInfo, type ReactNode } from 'react'
import { ErrorState } from './States'

interface Props {
  children: ReactNode
  /** Changing this (e.g. the route) clears a previous error. */
  resetKey?: string
}

interface State {
  error: Error | null
  key: string | undefined
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, key: this.props.resetKey }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    return props.resetKey !== state.key ? { error: null, key: props.resetKey } : null
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Page crashed', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="pt-space-lg">
          <ErrorState
            title="This page crashed"
            error={this.state.error}
            onRetry={() => this.setState({ error: null })}
          />
        </div>
      )
    }
    return this.props.children
  }
}
