async function main() {
	const proc = Bun.spawn([
		"bunx",
		"attw",
		"-f",
		"table-flipped",
		"--no-emoji",
		"--no-color",
		"--pack",
	]);

	const text = await new Response(proc.stdout).text();

	const entrypointLines = text
		.slice(text.indexOf('"remix-i18next/'))
		.split("\n")
		.filter(Boolean)
		.filter((line) => !line.includes("─"))
		.map((line) =>
			line
				.replaceAll(/[^\d "()/A-Za-z│-]/g, "")
				.replaceAll("90m│39m", "│")
				.replaceAll(/^│/g, "")
				.replaceAll(/│$/g, ""),
		);

	const pkg = await Bun.file("package.json").json();
	const entrypoints = entrypointLines.map((entrypointLine) => {
		const [entrypoint, ...resolutionColumns] = entrypointLine.split("│");
		if (!entrypoint) throw new Error("Entrypoint not found");
		if (!resolutionColumns[2]) throw new Error("ESM resolution not found");
		if (!resolutionColumns[3]) throw new Error("Bundler resolution not found");
		return {
			entrypoint: entrypoint.replace(pkg.name, ".").trim(),
			esm: resolutionColumns[2].trim(),
			bundler: resolutionColumns[3].trim(),
		};
	});

	const entrypointsWithProblems = entrypoints.filter(
		(item) => item.esm.includes("fail") || item.bundler.includes("fail"),
	);

	if (entrypointsWithProblems.length > 0) {
		console.error("Entrypoints with problems:");
		process.exit(1);
	}
}

await main().catch((error) => {
	console.error(error);
	process.exit(1);
});

export {};
