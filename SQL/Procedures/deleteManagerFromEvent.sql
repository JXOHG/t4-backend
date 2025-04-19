DELIMITER $$

CREATE PROCEDURE RemoveManager(IN input_user_id INT, IN input_event_id INT)
BEGIN
    DELETE FROM Manages WHERE input_user_id = user_id AND input_event_id = event_id;
END $$

DELIMITER ;