const config = {
  branches: ['main', 'master'],

  "plugins": [
    [
      "@semantic-release/commit-analyzer",
      {
        "releaseRules": [
          { "type": "major", "release": "major" }
        ]
      }
    ],
    "@semantic-release/release-notes-generator",
    [
      "@semantic-release/changelog",
      {
        "changelogFile": "CHANGELOG.md"
      }
    ],
    [
      "@semantic-release/exec",
      {
        "prepareCmd": "echo ${nextRelease.version} > .VERSION && uv version ${nextRelease.version} && uv build"
      }
    ],
    [
      "@semantic-release/git",
      {
        "assets": ["CHANGELOG.md", "pyproject.toml", ".VERSION"],
        "message": "chore(Release 🚀): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}"
      }
    ],
    [
      "@semantic-release/github",
      {
        "assets": [
          { "path": "dist/*.whl", "label": "Python Wheel" },
          { "path": "dist/*.tar.gz", "label": "Source Distribution" }
        ],
        "successComment": false,
        "failComment": false,
        "releasedLabels": false,
        "addReleases": "bottom"
      }
    ]
  ],
};
module.exports = config;
