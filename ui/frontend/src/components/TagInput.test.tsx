import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import TagInput from "./TagInput";

describe("TagInput", () => {
  it("renders existing values as pills", () => {
    render(<TagInput value={["us-east-1", "us-west-2"]} onChange={vi.fn()} />);
    expect(screen.getByText("us-east-1")).toBeInTheDocument();
    expect(screen.getByText("us-west-2")).toBeInTheDocument();
  });

  it("adds a tag on Enter and clears the input", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<TagInput value={[]} onChange={onChange} placeholder="type here" />);
    const input = screen.getByPlaceholderText("type here");
    await user.type(input, "us-east-1{Enter}");
    expect(onChange).toHaveBeenCalledWith(["us-east-1"]);
  });

  it("commits on comma", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<TagInput value={[]} onChange={onChange} />);
    const input = screen.getByRole("textbox");
    await user.type(input, "iam,");
    expect(onChange).toHaveBeenCalledWith(["iam"]);
  });

  it("commits on space", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<TagInput value={[]} onChange={onChange} />);
    const input = screen.getByRole("textbox");
    await user.type(input, "iam ");
    expect(onChange).toHaveBeenCalledWith(["iam"]);
  });

  it("does not add a duplicate tag", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<TagInput value={["iam"]} onChange={onChange} />);
    const input = screen.getByRole("textbox");
    await user.type(input, "iam{Enter}");
    expect(onChange).not.toHaveBeenCalled();
  });

  it("removes the last tag on backspace when the input is empty", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<TagInput value={["iam", "s3"]} onChange={onChange} />);
    const input = screen.getByRole("textbox");
    await user.click(input);
    await user.keyboard("{Backspace}");
    expect(onChange).toHaveBeenCalledWith(["iam"]);
  });

  it("does not remove a tag on backspace while the input has text", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<TagInput value={["iam"]} onChange={onChange} />);
    const input = screen.getByRole("textbox");
    await user.type(input, "s3");
    onChange.mockClear();
    await user.keyboard("{Backspace}");
    expect(onChange).not.toHaveBeenCalled();
  });

  it("removes a tag when its remove button is clicked", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<TagInput value={["iam", "s3"]} onChange={onChange} />);
    await user.click(screen.getByLabelText("Remove iam"));
    expect(onChange).toHaveBeenCalledWith(["s3"]);
  });

  it("commits the draft on blur", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <div>
        <TagInput value={[]} onChange={onChange} />
        <button type="button">elsewhere</button>
      </div>,
    );
    const input = screen.getByRole("textbox");
    await user.type(input, "iam");
    await user.click(screen.getByText("elsewhere"));
    expect(onChange).toHaveBeenCalledWith(["iam"]);
  });

  it("does not add a tag for whitespace-only input", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <div>
        <TagInput value={[]} onChange={onChange} />
        <button type="button">elsewhere</button>
      </div>,
    );
    const input = screen.getByRole("textbox");
    await user.type(input, "   ");
    await user.click(screen.getByText("elsewhere"));
    expect(onChange).not.toHaveBeenCalled();
  });

  it("shows the placeholder only when there are no tags", () => {
    const { rerender } = render(<TagInput value={[]} onChange={vi.fn()} placeholder="add one" />);
    expect(screen.getByPlaceholderText("add one")).toBeInTheDocument();
    rerender(<TagInput value={["iam"]} onChange={vi.fn()} placeholder="add one" />);
    expect(screen.queryByPlaceholderText("add one")).not.toBeInTheDocument();
  });
});
