DELIMITER $$

CREATE PROCEDURE DeleteEvent(IN input_event_id INT)
BEGIN
    DELETE FROM Event WHERE input_event_id = event_id;
END $$

DELIMITER ;