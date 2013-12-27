Sajiki
------

**Sajiki** (*Gallery / Reviewing Box*) is a web-based photo management platform for categorizing, publishing and searching photographic material in an organization. This project aims at a seamless collaboration between PR/press, photographers and organization members.

### Main Features and Requirements:

* **Multiple users and fine-grained access control:** As a photographer I can decide which photos can be accessed by which user. I can also tag photos with user names so these users may review photos of themselves or generate publicly accessible links.

* **Automatic indexing:** As a photographer, when I export photos to a dedicated file storage, they show up in the web platform along with all metadata.

* **Semantic retrieval.** As a user I can search for tags, synonyms, hypernyms, time ranges, single persons, named groups of people, ratings, locations and events.

* **Fast tagging.** As a photographer I can quickly tag a large set of photos. I can automatically generate collections from tags

### Ideas

* **Timeline.** As a PR member I can see the latest photos on my start page
* **Feedback.** As a user I can vote and comment on photos or put in a veto on publishing a photo
* **Event planning.** As a user I can request certain events being covered by photographers, see which photographers are attending and which photos have already been uploaded during or after the event. As a photographer, I can announce my attendance and link photos to this event.

### Progress
The project is at a very early development stage. Code published here is currently not useful for anyone other than the developers.

## Technology

### Web Stack

* Application written in **Python** using the **bottle** Microframework for WSGI compliance.
* **Beaker** session management and cryptography
* **Jinja 2** template engine
* **Mongo DB** as flexible metadata storage.
* Homebrew Role-Based Access Control (RBAC) facility with additional Attribute-Based permissions (currently very instable, may be updated/rewritten frequently)
