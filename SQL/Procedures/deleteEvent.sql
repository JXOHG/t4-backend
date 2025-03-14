DELIMITER $$

CREATE PROCEDURE DeleteEvent(IN event_id INT)
BEGIN
    DELETE FROM Event WHERE event_id = event_id;
END $$

DELIMITER ;