DELIMITER $$

CREATE PROCEDURE UpdateEvent(
    IN p_event_id INT,
    IN p_title VARCHAR(100),
    IN p_description TEXT,
    IN p_event_date DATETIME,
    IN p_location VARCHAR(255)
)
BEGIN
    UPDATE Event
    SET 
        title = p_title, 
        description = p_description, 
        event_date = p_event_date, 
        location = p_location
    WHERE event_id = p_event_id;
END $$

DELIMITER ;