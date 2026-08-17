/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const collection = app.findCollectionByNameOrId("pbc_1704985774")

  // add field
  collection.fields.addAt(14, new Field({
    "autogeneratePattern": "",
    "help": "",
    "hidden": false,
    "id": "text3470521676",
    "max": 0,
    "min": 0,
    "name": "collector",
    "pattern": "",
    "presentable": false,
    "primaryKey": false,
    "required": false,
    "system": false,
    "type": "text"
  }))

  // add field
  collection.fields.addAt(15, new Field({
    "help": "",
    "hidden": false,
    "id": "json421552847",
    "maxSize": 2000000,
    "name": "plain",
    "presentable": false,
    "required": false,
    "system": false,
    "type": "json"
  }))

  // add field
  collection.fields.addAt(16, new Field({
    "autogeneratePattern": "",
    "help": "",
    "hidden": false,
    "id": "text2229534404",
    "max": 0,
    "min": 0,
    "name": "run_id",
    "pattern": "",
    "presentable": false,
    "primaryKey": false,
    "required": false,
    "system": false,
    "type": "text"
  }))

  // add field
  collection.fields.addAt(17, new Field({
    "help": "",
    "hidden": false,
    "id": "json3024723976",
    "maxSize": 2000000,
    "name": "population",
    "presentable": false,
    "required": false,
    "system": false,
    "type": "json"
  }))

  return app.save(collection)
}, (app) => {
  const collection = app.findCollectionByNameOrId("pbc_1704985774")

  // remove field
  collection.fields.removeById("text3470521676")

  // remove field
  collection.fields.removeById("json421552847")

  // remove field
  collection.fields.removeById("text2229534404")

  // remove field
  collection.fields.removeById("json3024723976")

  return app.save(collection)
})
