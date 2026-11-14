export function Preview({ html }: { html: string }) {
  // planted: unsanitised HTML
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Static() {
  // correct example (must not be flagged)
  return <div dangerouslySetInnerHTML={{ __html: "<b>fixed</b>" }} />;
}
