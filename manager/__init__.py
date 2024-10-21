from sanic import Blueprint, json, HTTPResponse

from manager.config import version

bp_manager = Blueprint('manager')
bg_manager = Blueprint.group(bp_manager)

@bp_manager.get('/version')
def version_endpoint(*_) -> HTTPResponse:
    """Return a JSON object with version information.

    openapi:
    ---
    responses:
      '200':
        description: Version information
        content:
          application/json:
            schema:
              type: object
              required:
                - version
                - major
                - minor
              properties:
                version:
                  type: string
                  description: The complete Mitigation Manager version string
                  examples:
                     - "v1.0"
                major:
                  type: integer
                  description: The major version
                  format: int32
                  examples:
                    - 1
                minor:
                  type: integer
                  description: The minor version
                  format: int32
                  examples:
                    - 0
    """
    return json({
        'version': f'v{version}',
        'major': int(version.split('.')[0]),
        'minor': int(version.split('.')[1]),
    })
