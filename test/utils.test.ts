import { fixedEncodeURIComponent } from "../src/utils";

describe(fixedEncodeURIComponent, () => {
  test("should encode string", () => {
    expect(fixedEncodeURIComponent("foo, bar")).toMatchInlineSnapshot(
      `"foo%2C%20bar"`
    );
    expect(
      fixedEncodeURIComponent(
        "https://na2hiro:foobar@localhost:3030/search?loc=Los+Angeles,%20CA"
      )
    ).toMatchInlineSnapshot(
      `"https%3A%2F%2Fna2hiro%3Afoobar%40localhost%3A3030%2Fsearch%3Floc%3DLos%2BAngeles%2C%2520CA"`
    );
    expect(
      fixedEncodeURIComponent("What's this? (woo hoo!)")
    ).toMatchInlineSnapshot(`"What%27s%20this%3F%20%28woo%20hoo%21%29"`);
  });
});
