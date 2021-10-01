# Data

Files in this directory contain additional data used by Dozer.

## github-repos-with-debian-based-dockerfiles.csv

This file contains GitHub repos with a root Dockerfile for a Debian based 
image that does not use a multistage build. It was generated from Google
BigQuery with the query

```sql
SELECT 
  dockerfile.repo repo
FROM (
  SELECT 
    files.repo_name repo, 
    contents.content content
  FROM 
    `bigquery-public-data.github_repos.files` files
  JOIN 
    `bigquery-public-data.github_repos.contents` contents
  ON 
    files.id=contents.id
  WHERE 
    files.path='Dockerfile' 
) dockerfile
WHERE 
      REGEXP_CONTAINS(dockerfile.content, r'^FROM (debian|ubuntu)')
  AND ARRAY_LENGTH(REGEXP_EXTRACT_ALL(dockerfile.content, r'^FROM')) = 1
GROUP BY repo
``` 
